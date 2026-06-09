#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing as mp
import queue
import tempfile
import time
from pathlib import Path
from typing import Any

from weall.runtime.apply.storage import apply_storage
from weall.runtime.tx_admission import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict[str, Any], *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, chain_id="batch569-ipfs-multiprocess", payload=payload, sig="sig", system=system, parent=parent)


def _worker(operator_id: str, root: str, inbox: mp.Queue, outbox: mp.Queue) -> None:
    base = Path(root) / operator_id
    base.mkdir(parents=True, exist_ok=True)
    running = True
    while running:
        cmd = inbox.get()
        op = cmd.get("op")
        cid = str(cmd.get("cid") or "")
        if op == "stop":
            running = False
        elif op == "add_pin":
            data = bytes.fromhex(str(cmd.get("data_hex") or ""))
            (base / cid).write_bytes(data)
            outbox.put({"operator_id": operator_id, "op": op, "cid": cid, "ok": True, "sha256": hashlib.sha256(data).hexdigest()})
        elif op == "cat":
            p = base / cid
            if p.exists():
                data = p.read_bytes()
                outbox.put({"operator_id": operator_id, "op": op, "cid": cid, "ok": True, "data_hex": data.hex(), "sha256": hashlib.sha256(data).hexdigest()})
            else:
                outbox.put({"operator_id": operator_id, "op": op, "cid": cid, "ok": False, "reason": "missing"})


def _seed_state(state: dict[str, Any], operators: list[str]) -> None:
    state.setdefault("accounts", {})
    node_ops = state.setdefault("roles", {}).setdefault("node_operators", {})
    node_ops["active_set"] = list(operators)
    by_id = node_ops.setdefault("by_id", {})
    storage = state.setdefault("storage", {})
    storage.setdefault("operators", {})
    for op in operators:
        state["accounts"][op] = {"poh_tier": 2, "storage_operator_eligible": True}
        by_id[op] = {"account_id": op, "enrolled": True, "active": True, "responsibilities": {"storage": {"opted_in": True, "active": True, "declared_capacity_bytes": 1000000, "proven_capacity_bytes": 1000000, "allocated_capacity_bytes": 0, "used_capacity_bytes": 0, "proof_status": "verified", "proof_expires_height": 99999}}}
        storage["operators"][op] = {"enabled": True, "capacity_bytes": 1000000, "used_bytes": 0}


def _recv(q: mp.Queue, timeout: float = 2.0) -> dict[str, Any]:
    try:
        return dict(q.get(timeout=timeout))
    except queue.Empty as exc:
        raise RuntimeError("worker_timeout") from exc


def run_harness() -> dict[str, Any]:
    data = b"weall batch 569 multiprocess ipfs-compatible sample"
    cid = "QmYwAPJzv5CZsnAzt8auVZRnGzr1rRkNvztNFVQVw1Gc7Y"
    operators = ["op-a", "op-b", "op-c", "op-d"]
    with tempfile.TemporaryDirectory(prefix="weall-b569-ipfs-mp-") as td:
        root = Path(td)
        inboxes: dict[str, mp.Queue] = {op: mp.Queue() for op in operators}
        outbox: mp.Queue = mp.Queue()
        procs: dict[str, mp.Process] = {}
        for op in operators:
            p = mp.Process(target=_worker, args=(op, str(root), inboxes[op], outbox), daemon=True)
            p.start(); procs[op] = p
        try:
            state: dict[str, Any] = {"height": 88, "params": {"ipfs_replication_factor": 2}, "accounts": {"SYSTEM": {"poh_tier": 0}}, "roles": {}, "storage": {}}
            _seed_state(state, operators)
            request = apply_storage(state, _env("IPFS_PIN_REQUEST", "SYSTEM", 1, {"pin_id": "pin-b569", "cid": cid, "replication_factor": 2, "size_bytes": len(data)}, system=True, parent="storage"))
            pin_id = str(request.get("pin_id") or "pin-b569")
            targets = list(state["storage"]["pins"][pin_id].get("targets") or [])
            failed = targets[0]
            # First target process dies before pin confirmation.
            procs[failed].terminate(); procs[failed].join(timeout=1.0)
            fail_receipt = apply_storage(state, _env("IPFS_PIN_CONFIRM", "SYSTEM", 2, {"pin_id": pin_id, "cid": cid, "operator_id": failed, "ok": False, "reason": "operator_process_failed"}, system=True, parent="storage"))
            reassigned = list(state["storage"]["pins"][pin_id].get("targets") or [])
            replacement = next(op for op in reassigned if op not in targets)
            inboxes[replacement].put({"op": "add_pin", "cid": cid, "data_hex": data.hex()})
            add_res = _recv(outbox)
            inboxes[replacement].put({"op": "cat", "cid": cid})
            cat_res = _recv(outbox)
            confirm = apply_storage(state, _env("IPFS_PIN_CONFIRM", "SYSTEM", 3, {"pin_id": pin_id, "cid": cid, "operator_id": replacement, "ok": True, "retrieval_ok": cat_res.get("data_hex") == data.hex(), "proof_hash": cat_res.get("sha256")}, system=True, parent="storage"))
            final_pin = state["storage"]["pins"][pin_id]
            return {
                "ok": bool(add_res.get("ok") and cat_res.get("data_hex") == data.hex() and final_pin.get("availability_status") == "available"),
                "batch": "569",
                "worker_model": "multiprocess_ipfs_compatible_operator_workers",
                "operator_count": len(operators),
                "failed_operator": failed,
                "failed_process_exitcode": procs[failed].exitcode,
                "failure_receipt": fail_receipt,
                "replacement_operator": replacement,
                "reassignment_recorded": replacement in reassigned,
                "replacement_add_result": add_res,
                "replacement_cat_result": {k: v for k, v in cat_res.items() if k != "data_hex"},
                "confirm_receipt": confirm,
                "retrieval_confirmed": final_pin.get("durability_status") == "retrieval_confirmed",
                "availability_status": final_pin.get("availability_status"),
                "retrieval_proof_count": len(final_pin.get("retrieval_proofs") or []),
                "public_decentralized_media_claimed": False,
            }
        finally:
            for op, q in inboxes.items():
                if procs[op].is_alive():
                    q.put({"op": "stop"})
            time.sleep(0.05)
            for p in procs.values():
                if p.is_alive():
                    p.terminate(); p.join(timeout=1.0)


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
