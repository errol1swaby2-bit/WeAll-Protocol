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
from rehearse_storage_operator_durability_v1_5 import _enable_storage_responsibility

CID = "QmYwAPJzv5CZsnAzt8auVTLuRtKfXVDRzi4PhN6dZm8D8h"


def _env(tx_type: str, signer: str, nonce: int, payload: dict[str, Any], *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, chain_id="batch542-storage", payload=payload, sig="sig", system=system, parent=parent)


def _write_operator_pin(root: Path, operator_id: str, cid: str, data: bytes) -> dict[str, Any]:
    d = root / operator_id
    d.mkdir(parents=True, exist_ok=True)
    path = d / cid
    path.write_bytes(data)
    return {"operator_id": operator_id, "path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size_bytes": path.stat().st_size}


def run_harness() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="weall-b542-storage-worker-") as td:
        root = Path(td)
        payload = b"weall batch 542 durable content\n"
        state: dict[str, Any] = {"height": 1, "accounts": {"@alice": {"nonce": 0, "poh_tier": 2}}, "storage": {"config": {"replication_factor": 1}}}
        for op in ["op-a", "op-b", "op-c"]:
            _enable_storage_responsibility(state, op, capacity=4096)
            apply_storage(state, _env("STORAGE_OFFER_CREATE", op, 10 + len(op), {"offer_id": f"offer-{op}", "operator_id": op, "capacity_bytes": 1024}))
        req = apply_storage(state, _env("IPFS_PIN_REQUEST", "@alice", 1, {"pin_id": "pin-live", "cid": CID, "size_bytes": len(payload), "replication_factor": 1}))
        targets = list(req.get("targets") or []) if isinstance(req, dict) else []
        failed_operator = targets[0] if targets else "op-a"
        replacement = next((op for op in ["op-a", "op-b", "op-c"] if op != failed_operator), "op-b")
        failure = apply_storage(state, _env("IPFS_PIN_CONFIRM", "SYSTEM", 2, {"pin_id": "pin-live", "operator_id": failed_operator, "ok": False}, system=True, parent="pin-live"))
        pin_after_failure = state.get("storage", {}).get("pins", {}).get("pin-live", {})
        replacement = str(pin_after_failure.get("latest_reassignment", {}).get("new_operator_id") or replacement)
        proof = _write_operator_pin(root, replacement, CID, payload)
        reread_ok = Path(proof["path"]).read_bytes() == payload
        confirm = apply_storage(state, _env("IPFS_PIN_CONFIRM", "SYSTEM", 3, {"pin_id": "pin-live", "operator_id": replacement, "ok": True, "retrieval_ok": reread_ok, "retrieval_sha256": proof["sha256"]}, system=True, parent="pin-live"))
        pin = state.get("storage", {}).get("pins", {}).get("pin-live", {})
        return {
            "ok": reread_ok and pin.get("availability_status") == "available" and pin.get("durability_status") == "retrieval_confirmed",
            "batch": "542",
            "worker_model": "local_operator_file_pin_worker",
            "failed_operator": failed_operator,
            "replacement_operator": replacement,
            "reassignment_recorded": bool(pin_after_failure.get("latest_reassignment", {}).get("reassigned")),
            "initial_targets": targets,
            "retrieval_confirmed": pin.get("durability_status") == "retrieval_confirmed",
            "availability_status": pin.get("availability_status"),
            "retrieval_proof_count": len(pin.get("retrieval_proofs") or []),
            "operator_file_sha256": proof["sha256"],
            "failure_receipt": failure,
            "confirmation_receipt": confirm,
        }


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
