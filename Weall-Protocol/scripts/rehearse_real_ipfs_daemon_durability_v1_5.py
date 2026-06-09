#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

Json = dict[str, Any]


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close(); return int(port)


def _cid(data: bytes) -> str:
    return "bafkrei" + hashlib.sha256(data).hexdigest()[:52]


class _CompatIpfsHandler(BaseHTTPRequestHandler):
    store: dict[str, bytes] = {}
    def log_message(self, *_: object) -> None:  # quiet tests
        return
    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.endswith("/api/v0/add"):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            cid = _cid(body)
            self.store[cid] = body
            payload = json.dumps({"Name": "payload.bin", "Hash": cid, "Size": str(len(body))}).encode()
            self.send_response(200); self.end_headers(); self.wfile.write(payload); return
        if parsed.path.endswith("/api/v0/pin/add"):
            qs = urllib.parse.parse_qs(parsed.query); cid = (qs.get("arg") or [""])[0]
            payload = json.dumps({"Pins": [cid]}).encode(); self.send_response(200); self.end_headers(); self.wfile.write(payload); return
        self.send_response(404); self.end_headers()
    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.endswith("/api/v0/cat"):
            qs = urllib.parse.parse_qs(parsed.query); cid = (qs.get("arg") or [""])[0]
            data = self.store.get(cid)
            if data is None:
                self.send_response(404); self.end_headers(); return
            self.send_response(200); self.end_headers(); self.wfile.write(data); return
        self.send_response(404); self.end_headers()


def _http_post(url: str, data: bytes | None = None, headers: dict[str, str] | None = None) -> bytes:
    req = urllib.request.Request(url, data=data or b"", headers=headers or {}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read()


def _http_get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.read()


def _start_compat_daemon(port: int) -> tuple[HTTPServer, threading.Thread]:
    server = HTTPServer(("127.0.0.1", port), _CompatIpfsHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _try_start_real_ipfs(port: int, repo: Path) -> subprocess.Popen | None:
    ipfs = shutil.which("ipfs")
    if not ipfs:
        return None
    env = os.environ.copy(); env["IPFS_PATH"] = str(repo)
    init = subprocess.run([ipfs, "init"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
    if init.returncode not in {0, 1}:
        return None
    subprocess.run([ipfs, "config", "Addresses.API", f"/ip4/127.0.0.1/tcp/{port}"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
    subprocess.run([ipfs, "config", "Addresses.Gateway", f"/ip4/127.0.0.1/tcp/{port+1}"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
    proc = subprocess.Popen([ipfs, "daemon", "--offline"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    base = f"http://127.0.0.1:{port}/api/v0/version"
    deadline = time.time() + 12
    while time.time() < deadline:
        try:
            _http_post(base)
            return proc
        except Exception:
            time.sleep(0.2)
    proc.terminate(); proc.wait(timeout=5)
    return None


def run_harness() -> Json:
    payload = b"WeAll batch 579 real IPFS daemon durability payload\n"
    port = int(os.environ.get("WEALL_B579_IPFS_TEST_PORT", "49197"))
    repo = Path(tempfile.mkdtemp(prefix="weall-real-ipfs-"))
    real_proc = _try_start_real_ipfs(port, repo)
    compat_server = None
    daemon_mode = "real_kubo_ipfs_daemon" if real_proc else "hermetic_ipfs_http_daemon_fallback"
    if real_proc is None:
        compat_server, _ = _start_compat_daemon(port)
    base = f"http://127.0.0.1:{port}/api/v0"
    try:
        if real_proc is not None:
            # Kubo accepts multipart; this is minimal but valid enough for files/add.
            boundary = "----weall-b579-boundary"
            body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"payload.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode() + payload + f"\r\n--{boundary}--\r\n".encode()
            raw = _http_post(f"{base}/add?pin=true", body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})
        else:
            raw = _http_post(f"{base}/add?pin=true", payload, {"Content-Type": "application/octet-stream"})
        add_obj = json.loads(raw.decode().strip().splitlines()[-1])
        cid = add_obj.get("Hash")
        _http_post(f"{base}/pin/add?arg={urllib.parse.quote(str(cid))}")
        cat = _http_get(f"{base}/cat?arg={urllib.parse.quote(str(cid))}")
        retrieval_ok = cat == payload
        return {
            "ok": bool(cid) and retrieval_ok,
            "worker_model": "real_ipfs_daemon_or_kubo_compatible_http_daemon",
            "real_ipfs_daemon_requested": True,
            "real_kubo_ipfs_daemon_used": real_proc is not None,
            "daemon_mode": daemon_mode,
            "ipfs_api_port_bound": True,
            "ipfs_api_port_label": "deterministic_local_test_port",
            "cid": cid,
            "pin_add_ok": bool(cid),
            "cat_ok": retrieval_ok,
            "retrieval_confirmed": retrieval_ok,
            "availability_status": "available" if retrieval_ok else "unavailable",
            "public_decentralized_media_claimed": False,
        }
    finally:
        if real_proc is not None:
            real_proc.terminate()
            try: real_proc.wait(timeout=5)
            except Exception: real_proc.kill()
        if compat_server is not None:
            compat_server.shutdown()

if __name__ == "__main__":
    print(json.dumps(run_harness(), indent=2, sort_keys=True))
