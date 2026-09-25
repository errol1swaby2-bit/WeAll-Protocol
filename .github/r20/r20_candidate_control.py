#!/usr/bin/env python3
from __future__ import annotations

import runpy
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
PROJECT_ROOT = REPO_ROOT / "Weall-Protocol"
ORIGINAL_COMMIT = "e59f4e695be9508bf22f2675b5ed6272dd983e98"
ORIGINAL_REL = ".github/r20/r20_candidate_control.py"
ORIGINAL_BLOB = "5cacead33675cae66b46c1d6286122811d20f4b8"
TEMP_IMPL = HERE / ".r20_candidate_control_original.py"


def _load_original_main():
    actual_blob = subprocess.check_output(
        ["git", "rev-parse", f"{ORIGINAL_COMMIT}:{ORIGINAL_REL}"],
        cwd=REPO_ROOT,
        text=True,
    ).strip()
    if actual_blob != ORIGINAL_BLOB:
        raise SystemExit(
            f"known-good r20 controller blob drift: {actual_blob} != {ORIGINAL_BLOB}"
        )
    source = subprocess.check_output(
        ["git", "show", f"{ORIGINAL_COMMIT}:{ORIGINAL_REL}"],
        cwd=REPO_ROOT,
    )
    TEMP_IMPL.write_bytes(source)
    namespace = runpy.run_path(str(TEMP_IMPL), run_name="r20_candidate_control_original")
    original_main = namespace.get("main")
    if not callable(original_main):
        raise SystemExit("known-good r20 controller has no callable main()")
    return original_main


def _replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one source match, found {count}")
    return text.replace(old, new, 1)


def _replace_span_once(text: str, start: str, end: str, new: str, *, label: str) -> str:
    if text.count(start) != 1:
        raise SystemExit(f"{label}: expected one start anchor, found {text.count(start)}")
    start_at = text.index(start)
    tail = text[start_at + len(start) :]
    if tail.count(end) != 1:
        raise SystemExit(f"{label}: expected one end anchor after start, found {tail.count(end)}")
    end_at = text.index(end, start_at + len(start))
    return text[:start_at] + new + text[end_at:]


def _apply_storage_lifecycle_regression_fix() -> None:
    storage_path = PROJECT_ROOT / "src" / "weall" / "runtime" / "apply" / "storage.py"
    text = storage_path.read_text(encoding="utf-8")

    text = _replace_once(
        text,
        '''    if not replacement:\n        rec["status"] = "degraded"\n        rec["durability_status"] = "degraded_no_spare_target"\n        return {\n            "reassigned": False,\n            "reason": "no_spare_target",\n            "failed_operator_id": failed_operator_id,\n            "active_targets": [t for t in targets if t != failed_operator_id],\n        }\n''',
        '''    if not replacement:\n        next_targets = sorted(t for t in targets if t != failed_operator_id)\n        rec["targets"] = next_targets\n        rec["status"] = "degraded"\n        rec["durability_status"] = "degraded_no_spare_target"\n        rec["availability_status"] = "degraded"\n        return {\n            "reassigned": False,\n            "reason": "no_spare_target",\n            "failed_operator_id": failed_operator_id,\n            "active_targets": list(next_targets),\n            "targets": list(next_targets),\n        }\n''',
        label="storage-no-spare-target-retirement",
    )

    text = _replace_once(
        text,
        '''    if release_requested:\n        confirmations.pop(operator_id, None)\n        size_bytes = _as_int(rec.get("size_bytes"), 0)\n        if size_bytes > 0:\n            _release_pin_accounting(state, pin_id, operator_id, int(size_bytes))\n        rec["status"] = "degraded" if confirmations else "released"\n''',
        '''    if release_requested:\n        confirmations.pop(operator_id, None)\n        size_bytes = _as_int(rec.get("size_bytes"), 0)\n        if size_bytes > 0:\n            _release_pin_accounting(state, pin_id, operator_id, int(size_bytes))\n        remaining_targets = [target for target in targets if target != operator_id]\n        rec["targets"] = remaining_targets\n        rec["status"] = "degraded" if remaining_targets else "released"\n        rec["durability_status"] = "under_replicated" if remaining_targets else "released"\n        rec["availability_status"] = "degraded" if remaining_targets else "unavailable"\n''',
        label="storage-release-retires-target",
    )

    text = _replace_span_once(
        text,
        "        if retrieval_ok:\n",
        "    else:\n        confirmations.pop(operator_id, None)\n",
        '''        if retrieval_ok:\n            proofs = (\n                rec.get("retrieval_proofs") if isinstance(rec.get("retrieval_proofs"), list) else []\n            )\n            proof = {\n                "operator_id": operator_id,\n                "at_nonce": int(env.nonce),\n                "at_height": int(_height(state)),\n                "cid": stored_cid,\n                "status": "retrievable",\n            }\n            if proof not in proofs:\n                proofs.append(proof)\n            rec["retrieval_proofs"] = proofs\n\n        retrievable_valid = [\n            op for op in valid if bool(_as_dict(confirmations.get(op)).get("retrieval_ok"))\n        ]\n        if len(retrievable_valid) >= required:\n            rec["durability_status"] = "retrieval_confirmed"\n            rec["availability_status"] = "available"\n        elif len(valid) >= required:\n            rec["durability_status"] = "replication_satisfied"\n            rec["availability_status"] = "degraded"\n        else:\n            rec["durability_status"] = "under_replicated"\n            rec["availability_status"] = "degraded"\n''',
        label="storage-retrieval-requires-replica-policy",
    )

    text = _replace_once(
        text,
        '        rec["latest_reassignment"] = reassignment\n',
        '        rec["latest_reassignment"] = reassignment\n        rec["availability_status"] = "degraded"\n',
        label="storage-failure-degrades-availability",
    )
    text = _replace_once(
        text,
        '    rec["confirmations"] = confirmations\n',
        '''    current_targets = sorted(\n        {str(target).strip() for target in rec.get("targets", []) if str(target).strip()}\n    )\n    rec["confirmed_target_count"] = len(\n        [target for target in current_targets if target in confirmations]\n    )\n    rec["confirmations"] = confirmations\n''',
        label="storage-confirmation-count-recompute",
    )
    storage_path.write_text(text, encoding="utf-8")

    test_path = PROJECT_ROOT / "tests" / "test_storage_pin_lifecycle_adversarial.py"
    if test_path.exists():
        raise SystemExit(f"unexpected pre-existing regression test: {test_path}")
    test_path.write_text(
        '''from __future__ import annotations\n\nimport pytest\n\nfrom weall.runtime.apply.storage import StorageApplyError\nfrom weall.runtime.domain_apply import apply_tx\nfrom weall.runtime.tx_admission import TxEnvelope\n\nCID_A = "bafkreigh2akiscaildc3qj6k2ol6qmk7p2xk3w5t2c5a7xqz7xqz7i"\n\n\ndef _env(\n    tx_type: str, signer: str, nonce: int, payload: dict | None = None, *, system: bool = False\n) -> TxEnvelope:\n    return TxEnvelope(\n        tx_type=tx_type,\n        signer=signer,\n        nonce=nonce,\n        payload=payload or {},\n        sig="sig",\n        parent=f"p:{max(0, nonce - 1)}" if system else None,\n        system=system,\n    )\n\n\ndef _operator_account(account_id: str, node_pubkey: str) -> dict:\n    return {\n        "poh_tier": 2,\n        "reputation_milli": 5000,\n        "devices": {\n            "by_id": {\n                f"device:{account_id}": {\n                    "device_id": f"device:{account_id}",\n                    "device_type": "node",\n                    "pubkey": node_pubkey,\n                    "revoked": False,\n                }\n            }\n        },\n    }\n\n\ndef _operator_role(account_id: str, node_pubkey: str, *, proven: int = 100_000) -> dict:\n    return {\n        "account_id": account_id,\n        "enrolled": True,\n        "active": True,\n        "node_pubkey": node_pubkey,\n        "responsibilities": {\n            "storage": {\n                "opted_in": True,\n                "active": True,\n                "proof_status": "verified",\n                "declared_capacity_bytes": proven,\n                "reserved_capacity_bytes": proven,\n                "probed_capacity_bytes": proven,\n                "proven_capacity_bytes": proven,\n                "allocated_capacity_bytes": 0,\n                "used_capacity_bytes": 0,\n                "proof_expires_height": 100,\n                "last_successful_challenge_height": 10,\n                "failed_challenge_count": 0,\n                "missed_challenge_count": 0,\n                "availability_score_milli": 1000,\n                "node_pubkey": node_pubkey,\n            }\n        },\n    }\n\n\ndef _operator_mirror(account_id: str, *, proven: int = 100_000) -> dict:\n    return {\n        "account_id": account_id,\n        "enabled": True,\n        "capacity_bytes": proven,\n        "used_bytes": 0,\n        "allocated_bytes": 0,\n        "allocated_capacity_bytes": 0,\n    }\n\n\ndef _state(*, operators: tuple[str, ...] = ("@op",), replication_factor: int = 1) -> dict:\n    accounts: dict[str, dict] = {}\n    by_id: dict[str, dict] = {}\n    mirrors: dict[str, dict] = {}\n    for index, account_id in enumerate(operators, start=1):\n        pubkey = f"node-pub-{index}"\n        accounts[account_id] = _operator_account(account_id, pubkey)\n        by_id[account_id] = _operator_role(account_id, pubkey)\n        mirrors[account_id] = _operator_mirror(account_id)\n    return {\n        "height": 10,\n        "params": {"ipfs_replication_factor": replication_factor},\n        "accounts": accounts,\n        "roles": {\n            "node_operators": {\n                "active_set": sorted(operators),\n                "by_id": by_id,\n            }\n        },\n        "storage": {\n            "operators": mirrors,\n            "pins": {},\n            "pin_confirms": [],\n            "offers": {},\n            "leases": {},\n            "proofs": {},\n            "challenges": {},\n            "capacity_challenges": {},\n            "reports": {},\n            "payouts": [],\n        },\n    }\n\n\ndef _request_pin(st: dict, *, nonce: int, size: int) -> dict:\n    return apply_tx(\n        st,\n        _env(\n            "IPFS_PIN_REQUEST",\n            "@user",\n            nonce,\n            {"pin_id": f"pin-{nonce}", "cid": CID_A, "size_bytes": size},\n        ),\n    )\n\n\ndef _storage(st: dict, account_id: str) -> dict:\n    return st["roles"]["node_operators"]["by_id"][account_id]["responsibilities"]["storage"]\n\n\ndef _confirm(\n    st: dict, *, pin_id: str, nonce: int, operator_id: str, ok: bool, **extra: object\n) -> dict:\n    payload = {\n        "pin_id": pin_id,\n        "cid": CID_A,\n        "operator_id": operator_id,\n        "ok": ok,\n        **extra,\n    }\n    return apply_tx(st, _env("IPFS_PIN_CONFIRM", "SYSTEM", nonce, payload, system=True))\n\n\ndef test_released_target_cannot_late_confirm_after_accounting_release() -> None:\n    st = _state()\n    pin = _request_pin(st, nonce=1, size=7_000)\n    operator_id = pin["targets"][0]\n    _confirm(st, pin_id=pin["pin_id"], nonce=2, operator_id=operator_id, ok=True)\n    _confirm(\n        st,\n        pin_id=pin["pin_id"],\n        nonce=3,\n        operator_id=operator_id,\n        ok=False,\n        release=True,\n    )\n\n    rec = st["storage"]["pins"][pin["pin_id"]]\n    assert rec["targets"] == []\n    assert rec["confirmed_target_count"] == 0\n    assert rec["status"] == "released"\n    assert _storage(st, operator_id)["allocated_capacity_bytes"] == 0\n    assert _storage(st, operator_id)["used_capacity_bytes"] == 0\n\n    with pytest.raises(StorageApplyError, match="operator_not_current_pin_target"):\n        _confirm(st, pin_id=pin["pin_id"], nonce=4, operator_id=operator_id, ok=True)\n\n    assert _storage(st, operator_id)["allocated_capacity_bytes"] == 0\n    assert _storage(st, operator_id)["used_capacity_bytes"] == 0\n\n\ndef test_failed_target_without_spare_is_retired_before_late_success() -> None:\n    st = _state()\n    pin = _request_pin(st, nonce=1, size=8_000)\n    operator_id = pin["targets"][0]\n    failed = _confirm(st, pin_id=pin["pin_id"], nonce=2, operator_id=operator_id, ok=False)\n\n    assert failed["reassignment"]["reassigned"] is False\n    assert failed["reassignment"]["reason"] == "no_spare_target"\n    rec = st["storage"]["pins"][pin["pin_id"]]\n    assert rec["targets"] == []\n    assert rec["confirmed_target_count"] == 0\n    assert _storage(st, operator_id)["allocated_capacity_bytes"] == 0\n\n    with pytest.raises(StorageApplyError, match="operator_not_current_pin_target"):\n        _confirm(st, pin_id=pin["pin_id"], nonce=3, operator_id=operator_id, ok=True)\n\n\ndef test_reassigned_pin_rejects_old_target_and_preserves_capacity_accounting() -> None:\n    st = _state(operators=("@op", "@op2"))\n    pin = _request_pin(st, nonce=1, size=8_000)\n    failed_operator = pin["targets"][0]\n    failed = _confirm(\n        st, pin_id=pin["pin_id"], nonce=2, operator_id=failed_operator, ok=False\n    )\n\n    assert failed["reassignment"]["reassigned"] is True\n    replacement = failed["reassignment"]["replacement_operator_id"]\n    assert replacement != failed_operator\n    assert st["storage"]["pins"][pin["pin_id"]]["targets"] == [replacement]\n\n    with pytest.raises(StorageApplyError, match="operator_not_current_pin_target"):\n        _confirm(st, pin_id=pin["pin_id"], nonce=3, operator_id=failed_operator, ok=True)\n\n    confirmed = _confirm(\n        st, pin_id=pin["pin_id"], nonce=4, operator_id=replacement, ok=True\n    )\n    assert confirmed["status"] == "confirmed"\n    assert confirmed["confirmed_target_count"] == 1\n    assert _storage(st, failed_operator)["allocated_capacity_bytes"] == 0\n    assert _storage(st, failed_operator)["used_capacity_bytes"] == 0\n    assert _storage(st, replacement)["allocated_capacity_bytes"] == 8_000\n    assert _storage(st, replacement)["used_capacity_bytes"] == 8_000\n\n\ndef test_global_availability_requires_retrieval_from_all_required_replicas() -> None:\n    st = _state(operators=("@op", "@op2"), replication_factor=2)\n    pin = _request_pin(st, nonce=1, size=6_000)\n    assert len(pin["targets"]) == 2\n    first, second = pin["targets"]\n\n    one = _confirm(\n        st,\n        pin_id=pin["pin_id"],\n        nonce=2,\n        operator_id=first,\n        ok=True,\n        retrieval_ok=True,\n    )\n    rec = st["storage"]["pins"][pin["pin_id"]]\n    assert one["status"] == "confirming"\n    assert one["confirmed_target_count"] == 1\n    assert rec["durability_status"] == "under_replicated"\n    assert rec["availability_status"] == "degraded"\n\n    two = _confirm(\n        st,\n        pin_id=pin["pin_id"],\n        nonce=3,\n        operator_id=second,\n        ok=True,\n        retrieval_ok=True,\n    )\n    rec = st["storage"]["pins"][pin["pin_id"]]\n    assert two["status"] == "confirmed"\n    assert two["confirmed_target_count"] == 2\n    assert rec["durability_status"] == "retrieval_confirmed"\n    assert rec["availability_status"] == "available"\n''',
        encoding="utf-8",
    )
    print("applied storage target-retirement, accounting, and replica-availability closure")


def _refresh_b517_completion_proof() -> None:
    generator = PROJECT_ROOT / "scripts" / "gen_b517_b521_completion_proof_v1_5.py"
    if not generator.is_file():
        raise SystemExit(f"missing deterministic B517-B521 generator: {generator}")
    subprocess.run([sys.executable, str(generator)], cwd=PROJECT_ROOT, check=True)
    subprocess.run([sys.executable, str(generator), "--check"], cwd=PROJECT_ROOT, check=True)
    print("refreshed deterministic B517-B521 completion proof and verified --check")


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        original_main = _load_original_main()
        rc = original_main()
        if rc not in (None, 0):
            raise SystemExit(f"known-good r20 controller failed: {rc}")
        if command == "post-apply":
            _apply_storage_lifecycle_regression_fix()
        if command == "verify-state":
            _refresh_b517_completion_proof()
        return 0
    finally:
        TEMP_IMPL.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
