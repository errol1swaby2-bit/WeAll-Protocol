#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any

from weall.runtime.apply.storage import apply_storage
from weall.runtime.tx_admission import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict[str, Any], *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, chain_id="batch558-storage-workers", payload=payload, sig="sig", system=system, parent=parent)


def _cid_for(data: bytes) -> str:
    # Known-good CIDv0 fixture used by the existing storage/media tests.
    return "QmYwAPJzv5CZsnAzt8auVZRnGzr1rRkNvztNFVQVw1Gc7Y"


class LocalOperatorWorker:
    def __init__(self, root: Path, operator_id: str) -> None:
        self.operator_id = operator_id
        self.root = root / operator_id
        self.root.mkdir(parents=True, exist_ok=True)
        self.failed = False

    def pin(self, cid: str, data: bytes) -> bool:
        if self.failed:
            return False
        (self.root / cid).write_bytes(data)
        return True

    def cat(self, cid: str) -> bytes | None:
        p = self.root / cid
        if not p.exists():
            return None
        return p.read_bytes()


def _seed_operator_state(state: dict[str, Any], operators: list[str]) -> None:
    state.setdefault("accounts", {})
    node_ops = state.setdefault("roles", {}).setdefault("node_operators", {})
    by_id = node_ops.setdefault("by_id", {})
    node_ops["active_set"] = list(operators)
    storage = state.setdefault("storage", {})
    storage.setdefault("operators", {})
    for op in operators:
        pubkey = f"node-key:{op}"
        state["accounts"][op] = {
            "poh_tier": 2,
            "storage_operator_eligible": True,
            "devices": {"by_id": {f"dev:{op}": {"device_type": "node", "pubkey": pubkey, "revoked": False}}},
        }
        by_id[op] = {
            "account_id": op,
            "enrolled": True,
            "active": True,
            "responsibilities": {
                "storage": {
                    "opted_in": True,
                    "active": True,
                    "declared_capacity_bytes": 1_000_000,
                    "proven_capacity_bytes": 1_000_000,
                    "allocated_capacity_bytes": 0,
                    "used_capacity_bytes": 0,
                    "proof_status": "verified",
                    "proof_expires_height": 10_000,
                    "availability_score_milli": 1000,
                }
            },
        }
        storage["operators"][op] = {"account_id": op, "enabled": True, "capacity_bytes": 1_000_000, "used_bytes": 0}


def run_harness() -> dict[str, Any]:
    data = b"weall batch 558 storage durability sample"
    cid = _cid_for(data)
    with tempfile.TemporaryDirectory(prefix="weall-b558-storage-workers-") as td:
        root = Path(td)
        operators = ["op-a", "op-b", "op-c", "op-d"]
        workers = {op: LocalOperatorWorker(root, op) for op in operators}
        state: dict[str, Any] = {"height": 40, "params": {"ipfs_replication_factor": 2}, "accounts": {"SYSTEM": {"poh_tier": 0}}, "roles": {}, "storage": {}}
        _seed_operator_state(state, operators)
        request = apply_storage(state, _env("IPFS_PIN_REQUEST", "SYSTEM", 1, {"pin_id": "pin-b558", "cid": cid, "replication_factor": 2, "size_bytes": len(data)}, system=True, parent="storage"))
        pin_id = str(request.get("pin_id") or "pin-b558")
        pin = state["storage"]["pins"][pin_id]
        targets = list(pin.get("targets") or pin.get("target_operators") or [])
        primary = targets[0]
        secondary = targets[1]
        workers[primary].failed = True
        primary_written = workers[primary].pin(cid, data)
        failed = apply_storage(state, _env("IPFS_PIN_CONFIRM", "SYSTEM", 2, {"pin_id": pin_id, "cid": cid, "operator_id": primary, "ok": False, "reason": "operator_failed"}, system=True, parent="storage"))
        reassigned_targets = list(state["storage"]["pins"][pin_id].get("targets") or state["storage"]["pins"][pin_id].get("target_operators") or [])
        replacement = next(op for op in reassigned_targets if op not in {primary, secondary})
        replacement_written = workers[replacement].pin(cid, data)
        replacement_read = workers[replacement].cat(cid)
        ok_confirm = apply_storage(state, _env("IPFS_PIN_CONFIRM", "SYSTEM", 3, {"pin_id": pin_id, "cid": cid, "operator_id": replacement, "ok": True, "retrieval_ok": replacement_read == data, "proof_hash": hashlib.sha256(replacement_read or b"").hexdigest()}, system=True, parent="storage"))
        final_pin = state["storage"]["pins"][pin_id]
        return {
            "ok": bool(not primary_written and replacement_written and replacement_read == data and final_pin.get("availability_status") == "available" and final_pin.get("durability_status") == "retrieval_confirmed"),
            "batch": "558",
            "worker_model": "multi_operator_local_file_pin_workers",
            "operator_count": len(operators),
            "initial_targets": targets,
            "failed_operator": primary,
            "replacement_operator": replacement,
            "reassigned_targets": reassigned_targets,
            "failure_receipt": failed,
            "replacement_confirm_receipt": ok_confirm,
            "retrieval_confirmed": final_pin.get("durability_status") == "retrieval_confirmed",
            "availability_status": final_pin.get("availability_status"),
            "retrieval_proof_count": len(final_pin.get("retrieval_proofs") or []),
            "public_decentralized_media_claimed": False,
        }


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
