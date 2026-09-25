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
    namespace = runpy.run_path(
        str(TEMP_IMPL),
        run_name="r20_candidate_control_original",
    )
    original_main = namespace.get("main")
    if not callable(original_main):
        raise SystemExit("known-good r20 controller has no callable main()")
    return original_main


def _replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one source match, found {count}")
    return text.replace(old, new, 1)


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

    text = _replace_once(
        text,
        '''        if retrieval_ok:\n            proofs = (\n                rec.get("retrieval_proofs") if isinstance(rec.get("retrieval_proofs"), list) else []\n            )\n            proof = {\n                "operator_id": operator_id,\n                "at_nonce": int(env.nonce),\n                "at_height": int(_height(state)),\n                "cid": stored_cid,\n                "status": "retrievable",\n            }\n            if proof not in proofs:\n                proofs.append(proof)\n            rec["retrieval_proofs"] = proofs\n            rec["durability_status"] = "retrieval_confirmed"\n            rec["availability_status"] = "available"\n        else:\n            rec["durability_status"] = (\n                "replication_satisfied" if len(valid) >= required else "under_replicated"\n            )\n''',
        '''        if retrieval_ok:\n            proofs = (\n                rec.get("retrieval_proofs") if isinstance(rec.get("retrieval_proofs"), list) else []\n            )\n            proof = {\n                "operator_id": operator_id,\n                "at_nonce": int(env.nonce),\n                "at_height": int(_height(state)),\n                "cid": stored_cid,\n                "status": "retrievable",\n            }\n            if proof not in proofs:\n                proofs.append(proof)\n            rec["retrieval_proofs"] = proofs\n\n        retrievable_valid = [\n            op for op in valid if bool(_as_dict(confirmations.get(op)).get("retrieval_ok"))\n        ]\n        if len(retrievable_valid) >= required:\n            rec["durability_status"] = "retrieval_confirmed"\n            rec["availability_status"] = "available"\n        elif len(valid) >= required:\n            rec["durability_status"] = "replication_satisfied"\n            rec["availability_status"] = "degraded"\n        else:\n            rec["durability_status"] = "under_replicated"\n            rec["availability_status"] = "degraded"\n''',
        label="storage-retrieval-requires-replica-policy",
    )

    text = _replace_once(
        text,
        '''        rec["latest_reassignment"] = reassignment\n        if not bool(reassignment.get("reassigned")) and rec.get("status") != "degraded":\n            rec["status"] = "degraded"\n\n    rec["confirmations"] = confirmations\n''',
        '''        rec["latest_reassignment"] = reassignment\n        rec["availability_status"] = "degraded"\n        if not bool(reassignment.get("reassigned")) and rec.get("status") != "degraded":\n            rec["status"] = "degraded"\n\n    current_targets = sorted(\n        {str(target).strip() for target in rec.get("targets", []) if str(target).strip()}\n    )\n    rec["confirmed_target_count"] = len(\n        [target for target in current_targets if target in confirmations]\n    )\n    rec["confirmations"] = confirmations\n''',
        label="storage-confirmation-count-recompute",
    )

    storage_path.write_text(text, encoding="utf-8")

    test_path = PROJECT_ROOT / "tests" / "test_storage_revalidation_and_accounting.py"
    tests = test_path.read_text(encoding="utf-8")
    tests = _replace_once(
        tests,
        "from weall.runtime.domain_apply import apply_tx\n",
        "import pytest\n\nfrom weall.runtime.apply.storage import StorageApplyError\nfrom weall.runtime.domain_apply import apply_tx\n",
        label="storage-regression-test-imports",
    )
    marker = "def test_released_pin_target_rejects_late_confirmation_after_accounting_release()"
    if marker in tests:
        raise SystemExit("storage lifecycle regression tests unexpectedly already present")

    tests += r'''


def _add_storage_operator(st: dict, account_id: str, *, node_pubkey: str) -> None:
    proven = 100_000
    st["accounts"][account_id] = {
        "poh_tier": 2,
        "reputation_milli": 5000,
        "devices": {
            "by_id": {
                f"device:{account_id}": {
                    "device_id": f"device:{account_id}",
                    "device_type": "node",
                    "pubkey": node_pubkey,
                    "revoked": False,
                }
            }
        },
    }
    st["roles"]["node_operators"]["active_set"].append(account_id)
    st["roles"]["node_operators"]["active_set"].sort()
    st["roles"]["node_operators"]["by_id"][account_id] = {
        "account_id": account_id,
        "enrolled": True,
        "active": True,
        "node_pubkey": node_pubkey,
        "responsibilities": {
            "storage": {
                "opted_in": True,
                "active": True,
                "proof_status": "verified",
                "declared_capacity_bytes": proven,
                "reserved_capacity_bytes": proven,
                "probed_capacity_bytes": proven,
                "proven_capacity_bytes": proven,
                "allocated_capacity_bytes": 0,
                "used_capacity_bytes": 0,
                "proof_expires_height": 100,
                "last_successful_challenge_height": st["height"],
                "failed_challenge_count": 0,
                "missed_challenge_count": 0,
                "availability_score_milli": 1000,
                "node_pubkey": node_pubkey,
            }
        },
    }
    st["storage"]["operators"][account_id] = {
        "account_id": account_id,
        "enabled": True,
        "capacity_bytes": proven,
        "used_bytes": 0,
        "allocated_bytes": 0,
        "allocated_capacity_bytes": 0,
    }


def _operator_storage(st: dict, account_id: str) -> dict:
    return st["roles"]["node_operators"]["by_id"][account_id]["responsibilities"]["storage"]


def test_released_pin_target_rejects_late_confirmation_after_accounting_release() -> None:
    st = _state(height=10, proof_expires_height=100)
    pin = _request_pin(st, nonce=1, size=7_000)
    operator_id = pin["targets"][0]

    apply_tx(
        st,
        _env(
            "IPFS_PIN_CONFIRM",
            "SYSTEM",
            2,
            {"pin_id": pin["pin_id"], "cid": CID_A, "operator_id": operator_id, "ok": True},
            system=True,
        ),
    )
    apply_tx(
        st,
        _env(
            "IPFS_PIN_CONFIRM",
            "SYSTEM",
            3,
            {
                "pin_id": pin["pin_id"],
                "cid": CID_A,
                "operator_id": operator_id,
                "release": True,
                "ok": False,
            },
            system=True,
        ),
    )

    rec = st["storage"]["pins"][pin["pin_id"]]
    assert rec["targets"] == []
    assert rec["confirmed_target_count"] == 0
    assert rec["status"] == "released"
    assert _operator_storage(st, operator_id)["allocated_capacity_bytes"] == 0
    assert _operator_storage(st, operator_id)["used_capacity_bytes"] == 0

    with pytest.raises(StorageApplyError, match="operator_not_current_pin_target"):
        apply_tx(
            st,
            _env(
                "IPFS_PIN_CONFIRM",
                "SYSTEM",
                4,
                {"pin_id": pin["pin_id"], "cid": CID_A, "operator_id": operator_id, "ok": True},
                system=True,
            ),
        )

    assert _operator_storage(st, operator_id)["allocated_capacity_bytes"] == 0
    assert _operator_storage(st, operator_id)["used_capacity_bytes"] == 0


def test_failed_pin_without_spare_retires_target_and_rejects_late_success() -> None:
    st = _state(height=10, proof_expires_height=100)
    pin = _request_pin(st, nonce=1, size=8_000)
    operator_id = pin["targets"][0]

    failed = apply_tx(
        st,
        _env(
            "IPFS_PIN_CONFIRM",
            "SYSTEM",
            2,
            {"pin_id": pin["pin_id"], "cid": CID_A, "operator_id": operator_id, "ok": False},
            system=True,
        ),
    )
    assert failed["reassignment"]["reassigned"] is False
    assert failed["reassignment"]["reason"] == "no_spare_target"
    rec = st["storage"]["pins"][pin["pin_id"]]
    assert rec["targets"] == []
    assert rec["confirmed_target_count"] == 0
    assert _operator_storage(st, operator_id)["allocated_capacity_bytes"] == 0

    with pytest.raises(StorageApplyError, match="operator_not_current_pin_target"):
        apply_tx(
            st,
            _env(
                "IPFS_PIN_CONFIRM",
                "SYSTEM",
                3,
                {"pin_id": pin["pin_id"], "cid": CID_A, "operator_id": operator_id, "ok": True},
                system=True,
            ),
        )


def test_failed_reassigned_target_rejects_old_late_confirmation_and_preserves_accounting() -> None:
    st = _state(height=10, proof_expires_height=100)
    _add_storage_operator(st, "@op2", node_pubkey="node-pub-2")
    pin = _request_pin(st, nonce=1, size=8_000)
    failed_operator = pin["targets"][0]

    failed = apply_tx(
        st,
        _env(
            "IPFS_PIN_CONFIRM",
            "SYSTEM",
            2,
            {
                "pin_id": pin["pin_id"],
                "cid": CID_A,
                "operator_id": failed_operator,
                "ok": False,
            },
            system=True,
        ),
    )
    assert failed["reassignment"]["reassigned"] is True
    replacement = failed["reassignment"]["replacement_operator_id"]
    assert replacement != failed_operator
    assert st["storage"]["pins"][pin["pin_id"]]["targets"] == [replacement]

    with pytest.raises(StorageApplyError, match="operator_not_current_pin_target"):
        apply_tx(
            st,
            _env(
                "IPFS_PIN_CONFIRM",
                "SYSTEM",
                3,
                {
                    "pin_id": pin["pin_id"],
                    "cid": CID_A,
                    "operator_id": failed_operator,
                    "ok": True,
                },
                system=True,
            ),
        )

    confirmed = apply_tx(
        st,
        _env(
            "IPFS_PIN_CONFIRM",
            "SYSTEM",
            4,
            {"pin_id": pin["pin_id"], "cid": CID_A, "operator_id": replacement, "ok": True},
            system=True,
        ),
    )
    assert confirmed["status"] == "confirmed"
    assert confirmed["confirmed_target_count"] == 1
    assert _operator_storage(st, failed_operator)["allocated_capacity_bytes"] == 0
    assert _operator_storage(st, failed_operator)["used_capacity_bytes"] == 0
    assert _operator_storage(st, replacement)["allocated_capacity_bytes"] == 8_000
    assert _operator_storage(st, replacement)["used_capacity_bytes"] == 8_000


def test_replication_factor_requires_all_current_targets_before_global_availability() -> None:
    st = _state(height=10, proof_expires_height=100)
    _add_storage_operator(st, "@op2", node_pubkey="node-pub-2")
    st["params"]["ipfs_replication_factor"] = 2
    pin = _request_pin(st, nonce=1, size=6_000)
    assert len(pin["targets"]) == 2

    first, second = pin["targets"]
    one = apply_tx(
        st,
        _env(
            "IPFS_PIN_CONFIRM",
            "SYSTEM",
            2,
            {
                "pin_id": pin["pin_id"],
                "cid": CID_A,
                "operator_id": first,
                "ok": True,
                "retrieval_ok": True,
            },
            system=True,
        ),
    )
    rec = st["storage"]["pins"][pin["pin_id"]]
    assert one["status"] == "confirming"
    assert one["confirmed_target_count"] == 1
    assert rec["durability_status"] == "under_replicated"
    assert rec["availability_status"] == "degraded"

    two = apply_tx(
        st,
        _env(
            "IPFS_PIN_CONFIRM",
            "SYSTEM",
            3,
            {
                "pin_id": pin["pin_id"],
                "cid": CID_A,
                "operator_id": second,
                "ok": True,
                "retrieval_ok": True,
            },
            system=True,
        ),
    )
    rec = st["storage"]["pins"][pin["pin_id"]]
    assert two["status"] == "confirmed"
    assert two["confirmed_target_count"] == 2
    assert rec["durability_status"] == "retrieval_confirmed"
    assert rec["availability_status"] == "available"
'''
    test_path.write_text(tests, encoding="utf-8")
    print("applied adversarial storage lifecycle/accounting closure and regression tests")


def _refresh_b517_completion_proof() -> None:
    generator = PROJECT_ROOT / "scripts" / "gen_b517_b521_completion_proof_v1_5.py"
    if not generator.is_file():
        raise SystemExit(f"missing deterministic B517-B521 generator: {generator}")

    subprocess.run(
        [sys.executable, str(generator)],
        cwd=PROJECT_ROOT,
        check=True,
    )
    subprocess.run(
        [sys.executable, str(generator), "--check"],
        cwd=PROJECT_ROOT,
        check=True,
    )
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
