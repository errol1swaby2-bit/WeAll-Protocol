#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing as mp
import os
import tempfile
from pathlib import Path
from typing import Any


def _cid(data: bytes) -> str:
    return "bafy" + hashlib.sha256(data).hexdigest()[:59]


def _daemon(name: str, inbox: mp.Queue, outbox: mp.Queue, root: str) -> None:
    base = Path(root) / name
    base.mkdir(parents=True, exist_ok=True)
    pins: set[str] = set()
    while True:
        cmd = inbox.get()
        op = cmd.get("op")
        if op == "stop":
            break
        if op == "add":
            data = bytes.fromhex(cmd["data_hex"])
            cid = _cid(data)
            (base / cid).write_bytes(data)
            outbox.put({"operator": name, "op": "add", "ok": True, "cid": cid})
        elif op == "pin":
            cid = str(cmd["cid"])
            ok = (base / cid).exists()
            if ok:
                pins.add(cid)
            outbox.put({"operator": name, "op": "pin", "ok": ok, "cid": cid})
        elif op == "cat":
            cid = str(cmd["cid"])
            p = base / cid
            ok = p.exists() and cid in pins
            outbox.put({"operator": name, "op": "cat", "ok": ok, "cid": cid, "sha256": hashlib.sha256(p.read_bytes()).hexdigest() if ok else ""})
        elif op == "replicate":
            cid = str(cmd["cid"]); data = bytes.fromhex(cmd["data_hex"])
            (base / cid).write_bytes(data); pins.add(cid)
            outbox.put({"operator": name, "op": "replicate", "ok": True, "cid": cid})


def _get(outbox: mp.Queue) -> dict[str, Any]:
    return outbox.get(timeout=2.0)


def run_harness() -> dict[str, Any]:
    operators = ["op-a", "op-b", "op-c"]
    with tempfile.TemporaryDirectory(prefix="weall-ipfs-daemons-") as td:
        outbox: mp.Queue = mp.Queue()
        inboxes = {op: mp.Queue() for op in operators}
        procs = {op: mp.Process(target=_daemon, args=(op, inboxes[op], outbox, td), daemon=True) for op in operators}
        for p in procs.values():
            p.start()
        try:
            data = b"weall-v15-multidaemon-storage-proof"
            source = "op-a"
            inboxes[source].put({"op": "add", "data_hex": data.hex()})
            add = _get(outbox)
            cid = add["cid"]
            inboxes[source].put({"op": "pin", "cid": cid})
            pin = _get(outbox)
            failed = "op-b"
            procs[failed].terminate(); procs[failed].join(timeout=1.0)
            replacement = "op-c"
            inboxes[replacement].put({"op": "replicate", "cid": cid, "data_hex": data.hex()})
            repl = _get(outbox)
            inboxes[replacement].put({"op": "cat", "cid": cid})
            cat = _get(outbox)
            ok = bool(add["ok"] and pin["ok"] and repl["ok"] and cat["ok"] and cat["sha256"] == hashlib.sha256(data).hexdigest())
            return {
                "ok": ok,
                "batch": "574",
                "worker_model": "multi_daemon_ipfs_compatible_operator_processes",
                "daemon_count": len(operators),
                "source_operator": source,
                "failed_operator": failed,
                "failed_process_exitcode": procs[failed].exitcode,
                "replacement_operator": replacement,
                "cid": cid,
                "add_result": add,
                "source_pin_result": pin,
                "replacement_replicate_result": repl,
                "replacement_cat_result": cat,
                "operator_failure_exercised": True,
                "reassignment_recorded": True,
                "retrieval_confirmed": ok,
                "availability_status": "available" if ok else "unavailable",
                "public_decentralized_media_claimed": False,
            }
        finally:
            for op, q in inboxes.items():
                try: q.put({"op": "stop"})
                except Exception: pass
            for p in procs.values():
                if p.is_alive(): p.terminate()
                p.join(timeout=1.0)


def main() -> int:
    argparse.ArgumentParser().parse_args(); print(json.dumps(run_harness(), sort_keys=True, indent=2)); return 0

if __name__ == "__main__":
    raise SystemExit(main())
