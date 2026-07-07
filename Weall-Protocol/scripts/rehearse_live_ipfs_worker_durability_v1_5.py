#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import http.server
import json
import os
import socket
import socketserver
import tempfile
import threading
from pathlib import Path
from typing import Any, Iterator

from weall.runtime.apply.storage import apply_storage
from weall.runtime.tx_admission import TxEnvelope
from weall.storage.ipfs_pin_worker import IpfsPinWorker, IpfsPinWorkerConfig
from rehearse_storage_operator_durability_v1_5 import _enable_storage_responsibility

CID = "QmYwAPJzv5CZsnAzt8auVTLuRtKfXVDRzi4PhN6dZm8D8h"


class _ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.bind(("127.0.0.1", 0)); port = int(s.getsockname()[1]); s.close(); return port


@contextlib.contextmanager
def _ipfs_api(status: int) -> Iterator[dict[str, Any]]:
    state: dict[str, Any] = {"requests": []}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            state["requests"].append({"path": self.path, "method": "POST"})
            self.send_response(int(status)); self.end_headers(); self.wfile.write(b'{"Pins":[]}')
        def log_message(self, *_: Any) -> None:
            return

    port = _free_port()
    srv = _ThreadedTCPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        state["url"] = f"http://127.0.0.1:{port}"
        yield state
    finally:
        srv.shutdown(); srv.server_close(); thread.join(timeout=1.0)


def _env(tx_type: str, signer: str, nonce: int, payload: dict[str, Any], *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, chain_id="batch546-ipfs-worker", payload=payload, sig="sig", system=system, parent=parent)


def _run_worker(db_path: Path, operator: str, url: str, *, max_attempts: int = 1) -> tuple[IpfsPinWorker, dict[str, Any]]:
    cfg = IpfsPinWorkerConfig(db_path=str(db_path), operator_account=operator, ipfs_enabled=True, ipfs_api_url=url, max_attempts=max_attempts, request_timeout_s=1)
    worker = IpfsPinWorker(cfg)
    return worker, worker.run_once()


def run_harness() -> dict[str, Any]:
    old_env = os.environ.copy()
    try:
        os.environ["WEALL_MODE"] = "testnet"
        with tempfile.TemporaryDirectory(prefix="weall-b546-live-ipfs-worker-") as td, _ipfs_api(500) as failing, _ipfs_api(200) as success:
            root = Path(td)
            db_path = root / "node.sqlite"
            state: dict[str, Any] = {"height": 1, "accounts": {"@alice": {"nonce": 0, "poh_tier": 2}}, "storage": {"config": {"replication_factor": 1}}}
            for op in ("op-a", "op-b", "op-c"):
                _enable_storage_responsibility(state, op, capacity=8192)
                apply_storage(state, _env("STORAGE_OFFER_CREATE", op, 10 + len(op), {"offer_id": f"offer-{op}", "operator_id": op, "capacity_bytes": 4096}))
            req = apply_storage(state, _env("IPFS_PIN_REQUEST", "@alice", 1, {"pin_id": "pin-b546", "cid": CID, "size_bytes": 32, "replication_factor": 1}))
            targets = list(req.get("targets") or []) if isinstance(req, dict) else []
            failed_operator = targets[0] if targets else "op-a"
            failed_worker = IpfsPinWorker(IpfsPinWorkerConfig(db_path=str(db_path), operator_account=failed_operator, ipfs_enabled=True, ipfs_api_url=str(failing["url"]), max_attempts=1, request_timeout_s=1))
            enqueue = failed_worker.enqueue_job(CID, targets=[failed_operator], meta={"pin_id": "pin-b546"})
            failed_stats = failed_worker.run_once()
            failure = apply_storage(state, _env("IPFS_PIN_CONFIRM", "SYSTEM", 2, {"pin_id": "pin-b546", "operator_id": failed_operator, "ok": False}, system=True, parent="pin-b546"))
            pin_after_failure = state.get("storage", {}).get("pins", {}).get("pin-b546", {})
            replacement = str(pin_after_failure.get("latest_reassignment", {}).get("new_operator_id") or "op-b")
            replacement_worker = IpfsPinWorker(IpfsPinWorkerConfig(db_path=str(db_path), operator_account=replacement, ipfs_enabled=True, ipfs_api_url=str(success["url"]), max_attempts=1, request_timeout_s=1))
            enqueue_replacement = replacement_worker.enqueue_job(CID, targets=[replacement], meta={"pin_id": "pin-b546", "replacement_for": failed_operator})
            success_stats = replacement_worker.run_once()
            confirm = apply_storage(state, _env("IPFS_PIN_CONFIRM", "SYSTEM", 3, {"pin_id": "pin-b546", "operator_id": replacement, "ok": True, "retrieval_ok": True}, system=True, parent="pin-b546"))
            pin = state.get("storage", {}).get("pins", {}).get("pin-b546", {})
            return {
                "ok": bool(failed_stats.get("failed") == 1 and success_stats.get("pinned") == 1 and pin.get("availability_status") == "available"),
                "batch": "546",
                "worker_model": "IpfsPinWorker_with_local_http_ipfs_api",
                "ipfs_enabled": True,
                "failure_api_requests": len(failing.get("requests") or []),
                "success_api_requests": len(success.get("requests") or []),
                "enqueue_initial": enqueue,
                "enqueue_replacement": enqueue_replacement,
                "failed_operator": failed_operator,
                "replacement_operator": replacement,
                "failed_worker_stats": failed_stats,
                "replacement_worker_stats": success_stats,
                "reassignment_recorded": bool(pin_after_failure.get("latest_reassignment", {}).get("reassigned")),
                "retrieval_confirmed": pin.get("durability_status") == "retrieval_confirmed",
                "availability_status": pin.get("availability_status"),
                "retrieval_proof_count": len(pin.get("retrieval_proofs") or []),
                "failure_receipt": failure,
                "confirmation_receipt": confirm,
            }
    finally:
        os.environ.clear(); os.environ.update(old_env)


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
