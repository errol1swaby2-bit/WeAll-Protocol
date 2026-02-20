# projects/Weall-Protocol/src/weall/api/ipfs.py
from __future__ import annotations

import json
import os
import urllib.parse
from dataclasses import dataclass
from io import BytesIO
from typing import BinaryIO, Dict, Optional, Tuple
import http.client


Json = Dict[str, object]


@dataclass(frozen=True)
class IpfsConfig:
    api_base: str
    gateway_base: str


def _cfg() -> IpfsConfig:
    api_base = (os.getenv("WEALL_IPFS_API_BASE") or "http://127.0.0.1:5001").strip()
    gateway_base = (os.getenv("WEALL_IPFS_GATEWAY_BASE") or "http://127.0.0.1:8080").strip()
    return IpfsConfig(api_base=api_base.rstrip("/"), gateway_base=gateway_base.rstrip("/"))


def ipfs_gateway_url(cid: str) -> str:
    cid = (cid or "").strip()
    if not cid:
        return ""
    cfg = _cfg()
    if not cfg.gateway_base:
        return ""
    return f"{cfg.gateway_base}/ipfs/{cid}"


def _send_chunk(conn: http.client.HTTPConnection, data: bytes) -> None:
    if not data:
        return
    conn.send(f"{len(data):X}\r\n".encode("ascii"))
    conn.send(data)
    conn.send(b"\r\n")


def _finish_chunks(conn: http.client.HTTPConnection) -> None:
    conn.send(b"0\r\n\r\n")


def _parse_ipfs_add_response(raw: bytes) -> Tuple[str, int]:
    """
    IPFS /api/v0/add returns NDJSON (one JSON per line).
    We take the last valid JSON object and extract Hash + Size.
    """
    txt = raw.decode("utf-8", errors="replace").strip()
    if not txt:
        raise RuntimeError("ipfs_add_failed:empty_response")

    last_obj: Optional[dict] = None
    for line in txt.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict):
            last_obj = obj

    if not isinstance(last_obj, dict):
        raise RuntimeError(f"ipfs_add_failed:bad_response:{txt[:200]}")

    cid = str(last_obj.get("Hash") or "").strip()
    size_s = str(last_obj.get("Size") or "0").strip()
    try:
        size = int(size_s)
    except Exception:
        size = 0

    if not cid:
        raise RuntimeError(f"ipfs_add_failed:missing_hash:{last_obj!r}")

    return cid, size


def ipfs_add_fileobj(*, name: str, fileobj: BinaryIO, pin: bool) -> Tuple[str, int]:
    """
    Stream a file-like object to IPFS via HTTP API without loading into memory.

    Uses chunked transfer encoding to avoid buffering the whole multipart body.

    Returns (cid, size)
    """
    cfg = _cfg()
    if not cfg.api_base:
        raise RuntimeError("ipfs_disabled:WEALL_IPFS_API_BASE is empty")

    u = urllib.parse.urlparse(cfg.api_base)
    scheme = (u.scheme or "http").lower()
    host = u.hostname or "127.0.0.1"
    port = int(u.port or (443 if scheme == "https" else 80))

    qs = urllib.parse.urlencode(
        {
            "pin": "true" if pin else "false",
            "wrap-with-directory": "false",
            "progress": "false",
        }
    )
    path = f"/api/v0/add?{qs}"

    conn: http.client.HTTPConnection
    if scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=30)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=30)

    boundary = "----weall-ipfs-boundary-7b3f2d6f9a3a4b8a"
    filename = (name or "upload").strip() or "upload"

    preamble = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n"
        f"\r\n"
    ).encode("utf-8")

    epilogue = f"\r\n--{boundary}--\r\n".encode("utf-8")

    try:
        conn.putrequest("POST", path)
        conn.putheader("Host", host)
        conn.putheader("Content-Type", f"multipart/form-data; boundary={boundary}")
        conn.putheader("Transfer-Encoding", "chunked")
        conn.endheaders()

        _send_chunk(conn, preamble)

        # Stream file content
        while True:
            chunk = fileobj.read(1024 * 256)
            if not chunk:
                break
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8")
            _send_chunk(conn, chunk)

        _send_chunk(conn, epilogue)
        _finish_chunks(conn)

        resp = conn.getresponse()
        body = resp.read()

        if resp.status < 200 or resp.status >= 300:
            # Try to surface IPFS error payload if any.
            msg = body.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"ipfs_add_failed:http_{resp.status}:{msg[:300]}")

        return _parse_ipfs_add_response(body)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def ipfs_add_bytes(*, name: str, data: bytes, pin: bool) -> Tuple[str, int]:
    """
    Backward-compatible helper: adds bytes to IPFS.
    This DOES allocate the bytes in memory (caller already has them).
    """
    bio = BytesIO(data)
    return ipfs_add_fileobj(name=name, fileobj=bio, pin=pin)
