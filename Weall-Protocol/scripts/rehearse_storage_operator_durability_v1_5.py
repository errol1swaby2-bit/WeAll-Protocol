#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from weall.runtime.apply.storage import apply_storage
from weall.runtime.tx_admission import TxEnvelope




def _enable_storage_responsibility(state: dict[str, Any], operator_id: str, *, capacity: int = 4096) -> None:
    roles = state.setdefault("roles", {}) if isinstance(state.get("roles"), dict) else {}
    state["roles"] = roles
    node_ops = roles.setdefault("node_operators", {}) if isinstance(roles.get("node_operators"), dict) else {}
    roles["node_operators"] = node_ops
    active = node_ops.setdefault("active_set", []) if isinstance(node_ops.get("active_set"), list) else []
    node_ops["active_set"] = active
    if operator_id not in active:
        active.append(operator_id)
    by_id = node_ops.setdefault("by_id", {}) if isinstance(node_ops.get("by_id"), dict) else {}
    node_ops["by_id"] = by_id
    by_id[operator_id] = {
        "account_id": operator_id,
        "status": "active",
        "active": True,
        "enrolled": True,
        "node_pubkey": f"{operator_id}-node",
        "devices": [{"device_type": "node", "public_key": f"{operator_id}-node", "active": True}],
        "responsibilities": {
            "storage": {
                "opted_in": True,
                "active": True,
                "proof_status": "verified",
                "declared_capacity_bytes": int(capacity),
                "reserved_capacity_bytes": int(capacity),
                "probed_capacity_bytes": int(capacity),
                "proven_capacity_bytes": int(capacity),
                "allocated_capacity_bytes": 0,
                "used_capacity_bytes": 0,
                "proof_expires_height": 10000,
            }
        },
    }
    accounts = state.setdefault("accounts", {}) if isinstance(state.get("accounts"), dict) else {}
    state["accounts"] = accounts
    accounts.setdefault(operator_id, {"poh_tier": 2, "reputation_milli": 2000})
    accounts[operator_id]["poh_tier"] = 2
    accounts[operator_id]["reputation_milli"] = 2000

def _env(tx_type: str, signer: str, nonce: int, payload: dict[str, Any] | None = None, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload or {}, sig="sig", system=system, parent=parent)


def run_harness() -> dict[str, Any]:
    state: dict[str, Any] = {"height": 100, "accounts": {"SYSTEM": {}}, "storage": {}}
    cid = "bafy" + "z" * 55
    for op in ["op-a", "op-b", "op-c"]:
        _enable_storage_responsibility(state, op, capacity=8192)
    apply_storage(state, _env("STORAGE_OFFER_CREATE", "@opA", 1, {"offer_id": "offer-a", "operator_id": "op-a", "capacity_bytes": 4096}))
    apply_storage(state, _env("STORAGE_OFFER_CREATE", "@opB", 2, {"offer_id": "offer-b", "operator_id": "op-b", "capacity_bytes": 4096}))
    apply_storage(state, _env("STORAGE_OFFER_CREATE", "@opC", 3, {"offer_id": "offer-c", "operator_id": "op-c", "capacity_bytes": 4096}))
    req = apply_storage(state, _env("IPFS_PIN_REQUEST", "SYSTEM", 4, {"pin_id": "pin-live", "cid": cid, "size_bytes": 128, "replication_factor": 2}, system=True, parent="storage"))
    pin_rec = state["storage"]["pins"]["pin-live"]
    targets = list(pin_rec.get("target_operator_ids") or pin_rec.get("targets") or [])
    failed_operator = targets[0]
    fail = apply_storage(state, _env("IPFS_PIN_CONFIRM", "SYSTEM", 5, {"pin_id": "pin-live", "cid": cid, "operator_id": failed_operator, "ok": False}, system=True, parent="storage"))
    replacement = fail.get("reassignment", {}).get("replacement_operator_id")
    if not replacement:
        replacement = next(op for op in ["op-a", "op-b", "op-c"] if op not in targets)
    ok = apply_storage(state, _env("IPFS_PIN_CONFIRM", "SYSTEM", 6, {"pin_id": "pin-live", "cid": cid, "operator_id": replacement, "ok": True, "retrieval_ok": True, "retrieval_probe_id": "probe-1"}, system=True, parent="storage"))
    rec = state["storage"]["pins"]["pin-live"]
    return {
        "ok": bool(req) and bool(fail.get("reassignment", {}).get("reassigned")) and bool(ok.get("ok")) and rec.get("durability_status") == "retrieval_confirmed",
        "batch": "538",
        "pin_id": "pin-live",
        "cid": cid,
        "initial_targets": targets,
        "failed_operator": failed_operator,
        "replacement_operator": replacement,
        "reassignment_recorded": bool(fail.get("reassignment", {}).get("reassigned")),
        "retrieval_confirmed": rec.get("durability_status") == "retrieval_confirmed",
        "availability_status": rec.get("availability_status"),
        "retrieval_proof_count": len(rec.get("retrieval_proofs") if isinstance(rec.get("retrieval_proofs"), list) else []),
        "operator_failure_recovery": "failed_pin_reassigned_then_retrieval_confirmed",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=None if args.json else 2))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
